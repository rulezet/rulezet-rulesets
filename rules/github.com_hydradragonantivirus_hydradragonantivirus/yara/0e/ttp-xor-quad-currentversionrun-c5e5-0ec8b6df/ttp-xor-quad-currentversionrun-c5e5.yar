rule TTP_XOR_QUAD_CurrentVersionRun_c5e5 {
  strings:
    $key_c5e5 = { 96 8a [2] b2 84 [2] 99 a8 [2] b7 8a [2] a3 91 [2] ac 8b [2] b2 96 [2] b0 97 [2] ab 91 [2] b7 96 [2] ab b9 }

  condition:
    any of them
}