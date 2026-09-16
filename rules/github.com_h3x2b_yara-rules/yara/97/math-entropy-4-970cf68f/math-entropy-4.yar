import "math"
rule math_entropy_4 : info statistics {
	meta:
	        description = "Low entropy - like plaintext or HTML or sparse data"

	condition:
		math.entropy(0, filesize) >= 4 and
		math.entropy(0, filesize) < 5
}