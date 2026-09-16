rule TTP_XOR_QUAD_CurrentVersionRun_f706 {
  strings:
    $key_f706 = { a4 69 [2] 80 67 [2] ab 4b [2] 85 69 [2] 91 72 [2] 9e 68 [2] 80 75 [2] 82 74 [2] 99 72 [2] 85 75 [2] 99 5a }

  condition:
    any of them
}