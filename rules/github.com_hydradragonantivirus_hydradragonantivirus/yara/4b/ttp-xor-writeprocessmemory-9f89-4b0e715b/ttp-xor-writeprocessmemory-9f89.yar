rule TTP_XOR_WriteProcessMemory_9f89 {
  strings:
    $key_9f89 = { c8 fb [2] fa d9 [2] fc ec [2] d2 ec [2] ed f0 }

  condition:
    any of them
}