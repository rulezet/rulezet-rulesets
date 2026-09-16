rule TTP_XOR_QUAD_CurrentVersionRun_c521 {
  strings:
    $key_c521 = { 96 4e [2] b2 40 [2] 99 6c [2] b7 4e [2] a3 55 [2] ac 4f [2] b2 52 [2] b0 53 [2] ab 55 [2] b7 52 [2] ab 7d }

  condition:
    any of them
}