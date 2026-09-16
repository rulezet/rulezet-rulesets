rule TTP_XOR_QUAD_CurrentVersionRun_e23c {
  strings:
    $key_e23c = { b1 53 [2] 95 5d [2] be 71 [2] 90 53 [2] 84 48 [2] 8b 52 [2] 95 4f [2] 97 4e [2] 8c 48 [2] 90 4f [2] 8c 60 }

  condition:
    any of them
}