import "math"
rule math_entropy_3 : info statistics {
	meta:
	        description = "Low entropy - very sparse data or repeating plaintext"

	condition:
		math.entropy(0, filesize) >= 3 and
		math.entropy(0, filesize) < 4
}