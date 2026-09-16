rule TTP_XOR_WriteProcessMemory_88ea {
  strings:
    $key_88ea = { df 98 [2] ed ba [2] eb 8f [2] c5 8f [2] fa 93 }

  condition:
    any of them
}