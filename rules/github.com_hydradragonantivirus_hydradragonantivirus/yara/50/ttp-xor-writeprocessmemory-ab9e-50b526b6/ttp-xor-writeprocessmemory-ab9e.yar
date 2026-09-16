rule TTP_XOR_WriteProcessMemory_ab9e {
  strings:
    $key_ab9e = { fc ec [2] ce ce [2] c8 fb [2] e6 fb [2] d9 e7 }

  condition:
    any of them
}