rule cobaltstrike_beacon_b64
{
    strings:
        $s1a = "JWQgaXMgYW4geDY0IHByb2Nlc3MgKGNhbid0IGluam"
        $s1b = "ZCBpcyBhbiB4NjQgcHJvY2VzcyAoY2FuJ3QgaW5qZW"
        $s1c = "IGlzIGFuIHg2NCBwcm9jZXNzIChjYW4ndCBpbmplY3"

        $s2a = "RmFpbGVkIHRvIGltcGVyc29uYXRlIGxvZ2dlZCBvbi"
        $s2b = "YWlsZWQgdG8gaW1wZXJzb25hdGUgbG9nZ2VkIG9uIH"
        $s2c = "aWxlZCB0byBpbXBlcnNvbmF0ZSBsb2dnZWQgb24gdX"

        $s3a = "cG93ZXJzaGVsbCAtbm9wIC1leGVjIGJ5cGFzcyAtRW"
        $s3b = "b3dlcnNoZWxsIC1ub3AgLWV4ZWMgYnlwYXNzIC1Fbm"
        $s3c = "d2Vyc2hlbGwgLW5vcCAtZXhlYyBieXBhc3MgLUVuY2"

        $s4a = "SUVYIChOZXctT2JqZWN0IE5ldC5XZWJjbGllbnQpLk"
        $s4b = "RVggKE5ldy1PYmplY3QgTmV0LldlYmNsaWVudCkuRG"
        $s4c = "WCAoTmV3LU9iamVjdCBOZXQuV2ViY2xpZW50KS5Eb3"

    condition:
        filesize < 1000KB and
        5 of ($s*)
}