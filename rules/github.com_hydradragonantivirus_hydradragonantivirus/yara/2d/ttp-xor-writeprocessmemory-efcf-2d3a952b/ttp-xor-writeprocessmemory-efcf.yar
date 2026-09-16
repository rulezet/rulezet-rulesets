rule TTP_XOR_WriteProcessMemory_efcf {
  strings:
    $key_efcf = { b8 bd [2] 8a 9f [2] 8c aa [2] a2 aa [2] 9d b6 }

  condition:
    any of them
}