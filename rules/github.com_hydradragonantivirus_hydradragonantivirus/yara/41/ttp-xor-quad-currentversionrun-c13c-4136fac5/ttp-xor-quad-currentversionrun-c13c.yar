rule TTP_XOR_QUAD_CurrentVersionRun_c13c {
  strings:
    $key_c13c = { 92 53 [2] b6 5d [2] 9d 71 [2] b3 53 [2] a7 48 [2] a8 52 [2] b6 4f [2] b4 4e [2] af 48 [2] b3 4f [2] af 60 }

  condition:
    any of them
}