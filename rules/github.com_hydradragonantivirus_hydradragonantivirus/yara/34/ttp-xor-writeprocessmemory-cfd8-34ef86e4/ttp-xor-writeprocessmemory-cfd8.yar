rule TTP_XOR_WriteProcessMemory_cfd8 {
  strings:
    $key_cfd8 = { 98 aa [2] aa 88 [2] ac bd [2] 82 bd [2] bd a1 }

  condition:
    any of them
}