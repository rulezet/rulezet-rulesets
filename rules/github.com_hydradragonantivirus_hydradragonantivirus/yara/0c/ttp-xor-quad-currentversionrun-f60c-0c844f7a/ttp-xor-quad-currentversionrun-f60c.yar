rule TTP_XOR_QUAD_CurrentVersionRun_f60c {
  strings:
    $key_f60c = { a5 63 [2] 81 6d [2] aa 41 [2] 84 63 [2] 90 78 [2] 9f 62 [2] 81 7f [2] 83 7e [2] 98 78 [2] 84 7f [2] 98 50 }

  condition:
    any of them
}