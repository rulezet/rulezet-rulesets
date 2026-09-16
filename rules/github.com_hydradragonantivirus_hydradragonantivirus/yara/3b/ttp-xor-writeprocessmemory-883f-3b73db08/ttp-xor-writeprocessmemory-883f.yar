rule TTP_XOR_WriteProcessMemory_883f {
  strings:
    $key_883f = { df 4d [2] ed 6f [2] eb 5a [2] c5 5a [2] fa 46 }

  condition:
    any of them
}