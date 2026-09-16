rule ct_size_100kb_1000kb {
  condition:
    filesize > 100KB and filesize < 1000KB
}