rule inMemPowerSniff: PowerSniff {
  meta:
    copyright = "root9b, LLC"

    authors = "Matt Weeks, Dax Morrow"

    description = "ShellTea + PoSlurp in Memory PowerSniff"

    reference = "https://www.root9b.com/newsroom/shelltea-poslurp-malware"

    version = "1.0"

    last_modified = "2017-06-27"

  strings:
    $wide_string = "/%s?user=%08x%08x%08x%08x&id=%u&ver=%u&os=%lu&os2=%lu&host=%u&k=%lu&type=%u" wide  
    $wide_string2 = "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT %u.%u%s)" wide  
  condition:
    all of them

}