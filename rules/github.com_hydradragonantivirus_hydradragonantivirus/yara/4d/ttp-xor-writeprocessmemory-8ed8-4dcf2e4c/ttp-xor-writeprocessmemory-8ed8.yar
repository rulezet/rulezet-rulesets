rule TTP_XOR_WriteProcessMemory_8ed8 {
  strings:
    $key_8ed8 = { d9 aa [2] eb 88 [2] ed bd [2] c3 bd [2] fc a1 }

  condition:
    any of them
}