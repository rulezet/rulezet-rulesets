rule TTP_XOR_WriteProcessMemory_6bcf {
  strings:
    $key_6bcf = { 3c bd [2] 0e 9f [2] 08 aa [2] 26 aa [2] 19 b6 }

  condition:
    any of them
}