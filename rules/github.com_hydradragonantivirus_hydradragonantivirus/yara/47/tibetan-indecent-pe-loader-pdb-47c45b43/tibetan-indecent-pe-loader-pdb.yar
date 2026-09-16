rule tibetan_indecent_pe_loader_pdb {
  meta:
    author = "Matt Brooks, @cmatthewbrooks"

  strings:
        $pdb = { 43 3a 5c 55 73 65 72 73 5c 6c 65 61 72 6e 5c 44 65 73 6b 74 6f 70 5c e5 85 8d e6 9d 80 }

  condition:
    all of them
}