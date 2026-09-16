rule TTP_XOR_QUAD_CurrentVersionRun_f791 {
  strings:
    $key_f791 = { a4 fe [2] 80 f0 [2] ab dc [2] 85 fe [2] 91 e5 [2] 9e ff [2] 80 e2 [2] 82 e3 [2] 99 e5 [2] 85 e2 [2] 99 cd }

  condition:
    any of them
}