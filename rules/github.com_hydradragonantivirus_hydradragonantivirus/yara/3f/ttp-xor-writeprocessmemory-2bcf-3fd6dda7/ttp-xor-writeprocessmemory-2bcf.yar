rule TTP_XOR_WriteProcessMemory_2bcf {
  strings:
    $key_2bcf = { 7c bd [2] 4e 9f [2] 48 aa [2] 66 aa [2] 59 b6 }

  condition:
    any of them
}