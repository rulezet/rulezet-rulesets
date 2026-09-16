rule TTP_XOR_WriteProcessMemory_ce99 {
  strings:
    $key_ce99 = { 99 eb [2] ab c9 [2] ad fc [2] 83 fc [2] bc e0 }

  condition:
    any of them
}