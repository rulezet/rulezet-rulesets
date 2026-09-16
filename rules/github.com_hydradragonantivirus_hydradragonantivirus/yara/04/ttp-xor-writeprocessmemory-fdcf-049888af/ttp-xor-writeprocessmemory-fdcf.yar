rule TTP_XOR_WriteProcessMemory_fdcf {
  strings:
    $key_fdcf = { aa bd [2] 98 9f [2] 9e aa [2] b0 aa [2] 8f b6 }

  condition:
    any of them
}