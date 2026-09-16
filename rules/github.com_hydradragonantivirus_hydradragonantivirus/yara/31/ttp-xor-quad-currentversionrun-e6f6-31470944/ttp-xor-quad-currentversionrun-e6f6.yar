rule TTP_XOR_QUAD_CurrentVersionRun_e6f6 {
  strings:
    $key_e6f6 = { b5 99 [2] 91 97 [2] ba bb [2] 94 99 [2] 80 82 [2] 8f 98 [2] 91 85 [2] 93 84 [2] 88 82 [2] 94 85 [2] 88 aa }

  condition:
    any of them
}