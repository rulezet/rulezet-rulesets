rule TTP_XOR_QUAD_CurrentVersionRun_b110 {
  strings:
    $key_b110 = { e2 7f [2] c6 71 [2] ed 5d [2] c3 7f [2] d7 64 [2] d8 7e [2] c6 63 [2] c4 62 [2] df 64 [2] c3 63 [2] df 4c }

  condition:
    any of them
}