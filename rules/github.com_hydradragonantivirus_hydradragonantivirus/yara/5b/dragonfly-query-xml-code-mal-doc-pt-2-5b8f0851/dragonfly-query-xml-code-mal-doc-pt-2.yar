rule Dragonfly_Query_XML_Code_MAL_DOC_PT_2

{

meta:

     name= "Query_XML_Code_MAL_DOC_PT_2"

     author = "other"

 

strings:

 

            $zip_magic = { 50 4b 03 04 }

            $dir1 = "word/_rels/settings.xml.rels"

            $bytes = {8c 90 cd 4e eb 30 10 85 d7}

 

condition:

            $zip_magic at 0 and $dir1 and $bytes

}