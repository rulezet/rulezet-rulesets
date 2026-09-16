rule TTP_XOR_WriteProcessMemory_9fdc {
  strings:
    $key_9fdc = { c8 ae [2] fa 8c [2] fc b9 [2] d2 b9 [2] ed a5 }

  condition:
    any of them
}