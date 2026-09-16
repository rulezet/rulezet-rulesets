rule TTP_XOR_WriteProcessMemory_8eda {
  strings:
    $key_8eda = { d9 a8 [2] eb 8a [2] ed bf [2] c3 bf [2] fc a3 }

  condition:
    any of them
}