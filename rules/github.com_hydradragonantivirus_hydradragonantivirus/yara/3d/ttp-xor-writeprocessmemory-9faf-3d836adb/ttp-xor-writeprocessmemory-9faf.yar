rule TTP_XOR_WriteProcessMemory_9faf {
  strings:
    $key_9faf = { c8 dd [2] fa ff [2] fc ca [2] d2 ca [2] ed d6 }

  condition:
    any of them
}