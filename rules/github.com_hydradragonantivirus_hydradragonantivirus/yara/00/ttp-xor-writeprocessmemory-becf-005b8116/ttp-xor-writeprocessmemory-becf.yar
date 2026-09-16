rule TTP_XOR_WriteProcessMemory_becf {
  strings:
    $key_becf = { e9 bd [2] db 9f [2] dd aa [2] f3 aa [2] cc b6 }

  condition:
    any of them
}