rule ELF_Chaos_RAT {
  meta:
     description = "Detects Linux ELF binaries <10MB with indicators of CHAOS-RAT-generated payloads"
     author = "Acronis TRU"
     date = "2025-04-16"
  strings:
     $chaos = "tiagorlampert/CHAOS" ascii
     $library1 = "BurntSushi/xgb" ascii
     $library2 = "gen2brain/shm" ascii
     $library3 = "kbinani/screenshot" ascii
  condition:
     uint32(0) == 0x464c457f and      filesize < 10MB and $chaos and
     2 of ($library*)
}