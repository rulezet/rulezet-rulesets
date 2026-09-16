rule TTP_XOR_WriteProcessMemory_1776 {
  strings:
    $key_1776 = { 40 04 [2] 72 26 [2] 74 13 [2] 5a 13 [2] 65 0f }

  condition:
    any of them
}