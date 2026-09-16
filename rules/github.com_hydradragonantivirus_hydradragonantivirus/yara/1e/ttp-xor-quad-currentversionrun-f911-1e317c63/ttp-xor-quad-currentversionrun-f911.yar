rule TTP_XOR_QUAD_CurrentVersionRun_f911 {
  strings:
    $key_f911 = { aa 7e [2] 8e 70 [2] a5 5c [2] 8b 7e [2] 9f 65 [2] 90 7f [2] 8e 62 [2] 8c 63 [2] 97 65 [2] 8b 62 [2] 97 4d }

  condition:
    any of them
}