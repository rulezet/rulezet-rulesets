rule TTP_XOR_QUAD_CurrentVersionRun_d021 {
  strings:
    $key_d021 = { 83 4e [2] a7 40 [2] 8c 6c [2] a2 4e [2] b6 55 [2] b9 4f [2] a7 52 [2] a5 53 [2] be 55 [2] a2 52 [2] be 7d }

  condition:
    any of them
}