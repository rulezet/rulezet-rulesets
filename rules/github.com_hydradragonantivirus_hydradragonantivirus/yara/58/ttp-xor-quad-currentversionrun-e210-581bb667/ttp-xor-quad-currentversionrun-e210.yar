rule TTP_XOR_QUAD_CurrentVersionRun_e210 {
  strings:
    $key_e210 = { b1 7f [2] 95 71 [2] be 5d [2] 90 7f [2] 84 64 [2] 8b 7e [2] 95 63 [2] 97 62 [2] 8c 64 [2] 90 63 [2] 8c 4c }

  condition:
    any of them
}