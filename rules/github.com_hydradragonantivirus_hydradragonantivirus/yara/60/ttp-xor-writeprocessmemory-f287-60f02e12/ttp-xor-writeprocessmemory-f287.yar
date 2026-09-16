rule TTP_XOR_WriteProcessMemory_f287 {
  strings:
    $key_f287 = { a5 f5 [2] 97 d7 [2] 91 e2 [2] bf e2 [2] 80 fe }

  condition:
    any of them
}