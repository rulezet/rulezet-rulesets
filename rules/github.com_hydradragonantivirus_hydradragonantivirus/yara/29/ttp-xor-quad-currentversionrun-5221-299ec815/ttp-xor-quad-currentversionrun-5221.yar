rule TTP_XOR_QUAD_CurrentVersionRun_5221 {
  strings:
    $key_5221 = { 01 4e [2] 25 40 [2] 0e 6c [2] 20 4e [2] 34 55 [2] 3b 4f [2] 25 52 [2] 27 53 [2] 3c 55 [2] 20 52 [2] 3c 7d }

  condition:
    any of them
}