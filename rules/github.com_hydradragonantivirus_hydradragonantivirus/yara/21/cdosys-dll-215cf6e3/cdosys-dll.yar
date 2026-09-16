rule cdosys_dll
{
       meta:
              description = "cdosys-dll"
              thread_level = 3
              in_the_wild = true
              reference = "https://www.optiv.com/blog/autoit-scripting-in-pos-malware"

       strings:
              $a = "Microsoft CDO for Windows Library" wide ascii
              $b = "CDOSYS.DLL" wide ascii

       condition:
              $a and $b
}