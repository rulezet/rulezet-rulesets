rule TTP_XOR_QUAD_CurrentVersionRun_c232 {
  strings:
    $key_c232 = { 91 5d [2] b5 53 [2] 9e 7f [2] b0 5d [2] a4 46 [2] ab 5c [2] b5 41 [2] b7 40 [2] ac 46 [2] b0 41 [2] ac 6e }

  condition:
    any of them
}