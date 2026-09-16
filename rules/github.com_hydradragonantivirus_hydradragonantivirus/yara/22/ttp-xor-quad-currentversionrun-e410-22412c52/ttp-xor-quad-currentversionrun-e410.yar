rule TTP_XOR_QUAD_CurrentVersionRun_e410 {
  strings:
    $key_e410 = { b7 7f [2] 93 71 [2] b8 5d [2] 96 7f [2] 82 64 [2] 8d 7e [2] 93 63 [2] 91 62 [2] 8a 64 [2] 96 63 [2] 8a 4c }

  condition:
    any of them
}