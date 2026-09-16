rule TTP_XOR_WriteProcessMemory_89cf {
  strings:
    $key_89cf = { de bd [2] ec 9f [2] ea aa [2] c4 aa [2] fb b6 }

  condition:
    any of them
}