rule TTP_XOR_QUAD_CurrentVersionRun_e208 {
  strings:
    $key_e208 = { b1 67 [2] 95 69 [2] be 45 [2] 90 67 [2] 84 7c [2] 8b 66 [2] 95 7b [2] 97 7a [2] 8c 7c [2] 90 7b [2] 8c 54 }

  condition:
    any of them
}