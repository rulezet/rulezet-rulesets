rule DarkComet_Config_Artifacts_Memory

{   

     meta:

           Description = "Looks for configuration artifacts from DarkComet. Works with memory dump and unpacked samples."

           filetype = "MemoryDump"         

           Author = "Ian Ahl @TekDefese"

           Date = "12-19-2013"

           reference = "http://www.tekdefense.com/news/2013/12/23/analyzing-darkcomet-in-memory.html"

     strings:

           $s0 = "GENCODE={" ascii

           $s1 = "MELT={" ascii

           $s2 = "COMBOPATH={" ascii

           $s3 = "NETDATA={" ascii

           $s4 = "PERSINST={" ascii

     condition:

           2 of them

}