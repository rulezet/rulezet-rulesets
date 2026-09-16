rule TTP_XOR_WriteProcessMemory_7dcf {
  strings:
    $key_7dcf = { 2a bd [2] 18 9f [2] 1e aa [2] 30 aa [2] 0f b6 }

  condition:
    any of them
}