rule TTP_XOR_QUAD_CurrentVersionRun_b021 {
  strings:
    $key_b021 = { e3 4e [2] c7 40 [2] ec 6c [2] c2 4e [2] d6 55 [2] d9 4f [2] c7 52 [2] c5 53 [2] de 55 [2] c2 52 [2] de 7d }

  condition:
    any of them
}