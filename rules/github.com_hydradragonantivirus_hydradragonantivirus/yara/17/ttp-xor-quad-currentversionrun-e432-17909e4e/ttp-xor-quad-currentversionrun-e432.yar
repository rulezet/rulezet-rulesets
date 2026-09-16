rule TTP_XOR_QUAD_CurrentVersionRun_e432 {
  strings:
    $key_e432 = { b7 5d [2] 93 53 [2] b8 7f [2] 96 5d [2] 82 46 [2] 8d 5c [2] 93 41 [2] 91 40 [2] 8a 46 [2] 96 41 [2] 8a 6e }

  condition:
    any of them
}