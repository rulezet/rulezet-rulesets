rule TTP_XOR_QUAD_CurrentVersionRun_b890 {
  strings:
    $key_b890 = { eb ff [2] cf f1 [2] e4 dd [2] ca ff [2] de e4 [2] d1 fe [2] cf e3 [2] cd e2 [2] d6 e4 [2] ca e3 [2] d6 cc }

  condition:
    any of them
}