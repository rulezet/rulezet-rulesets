rule TTP_XOR_QUAD_CurrentVersionRun_f73d {
  strings:
    $key_f73d = { a4 52 [2] 80 5c [2] ab 70 [2] 85 52 [2] 91 49 [2] 9e 53 [2] 80 4e [2] 82 4f [2] 99 49 [2] 85 4e [2] 99 61 }

  condition:
    any of them
}