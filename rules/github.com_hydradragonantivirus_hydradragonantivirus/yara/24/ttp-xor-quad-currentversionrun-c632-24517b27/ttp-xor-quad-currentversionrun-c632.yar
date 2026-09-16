rule TTP_XOR_QUAD_CurrentVersionRun_c632 {
  strings:
    $key_c632 = { 95 5d [2] b1 53 [2] 9a 7f [2] b4 5d [2] a0 46 [2] af 5c [2] b1 41 [2] b3 40 [2] a8 46 [2] b4 41 [2] a8 6e }

  condition:
    any of them
}