rule TTP_XOR_WriteProcessMemory_f1fd {
  strings:
    $key_f1fd = { a6 8f [2] 94 ad [2] 92 98 [2] bc 98 [2] 83 84 }

  condition:
    any of them
}