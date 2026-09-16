rule TTP_XOR_WriteProcessMemory_99fe {
  strings:
    $key_99fe = { ce 8c [2] fc ae [2] fa 9b [2] d4 9b [2] eb 87 }

  condition:
    any of them
}