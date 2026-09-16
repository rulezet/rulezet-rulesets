rule TTP_XOR_WriteProcessMemory_cbfe {
  strings:
    $key_cbfe = { 9c 8c [2] ae ae [2] a8 9b [2] 86 9b [2] b9 87 }

  condition:
    any of them
}