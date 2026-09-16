rule DarkComet_Keylogs_Memory

{   

     meta:

           Description = "Looks for key log artifacts"

           filetype = "MemoryDump"              

           Author = "Ian Ahl @TekDefese"

           Date = "12-20-2013"

           reference = "http://www.tekdefense.com/news/2013/12/23/analyzing-darkcomet-in-memory.html"


     strings:

           $s0 = "[<-]"

           $s1 = ":: Clipboard Change :"

           $s2 = "[LEFT]"

           $s4 = "[RIGHT]"

           $s5 = "[UP]"

           $s6 = "[DOWN]"

           $s7 = "[DEL]"

           $s8 = /::.{1,100}\(\d{1,2}:\d{1,2}:\d{1,2}\s\w{2}\)/  

     condition:

           any of them

}